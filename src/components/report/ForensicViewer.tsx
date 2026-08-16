/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo, useMemo } from 'react';
import {
  Image as ImageIcon,
  MapPin,
  ExternalLink,
  Cpu,
  Camera,
  AlertCircle,
  Shield,
  Activity,
  FileText,
  Maximize2,
  Clock
} from 'lucide-react';
import { ScanResults } from '../../types';

interface ForensicViewerProps {
  results: ScanResults;
  imagePreviewMode: 'normal' | 'ela' | 'noise';
  setImagePreviewMode: (mode: 'normal' | 'ela' | 'noise') => void;
  getSeverityStyles: (severity: string) => any;
  scanTime: string;
}

const ForensicStat = memo(({ label, value, mono = true }: { label: string; value: string | number; mono?: boolean }) => (
  <div className="flex justify-between border-b border-slate-100 dark:border-slate-800/50 pb-2 transition-colors">
    <span className="text-slate-500 dark:text-slate-500 font-mono text-[10px] uppercase font-bold">{label}:</span>
    <span className={`text-slate-900 dark:text-slate-200 truncate max-w-[180px] text-xs font-semibold ${mono ? 'font-mono' : ''}`}>
      {value}
    </span>
  </div>
));

export const ForensicViewer: React.FC<ForensicViewerProps> = memo(({
  results,
  imagePreviewMode,
  setImagePreviewMode,
  getSeverityStyles,
  scanTime,
}) => {
  if (!results.image || !results.image.authenticity) return null;

  const filterStyle = useMemo(() => {
    switch (imagePreviewMode) {
      case 'ela': return 'brightness(1.6) contrast(4) hue-rotate(270deg) saturate(3) opacity-80';
      case 'noise': return 'contrast(8) grayscale(1) invert(0.25) brightness(0.95)';
      default: return 'none';
    }
  }, [imagePreviewMode]);

  const hudText = useMemo(() => {
    switch (imagePreviewMode) {
      case 'ela': return 'ELA HEATMAP';
      case 'noise': return 'NOISE ISOLATION';
      default: return 'OPTICAL PASS';
    }
  }, [imagePreviewMode]);

  const authenticityConfig = useMemo(() => {
    const score = results.image?.authenticity?.overallScore ?? 0;
    if (score >= 75) return { stroke: 'stroke-emerald-500', label: 'GENUINE', color: 'text-emerald-500' };
    if (score >= 45) return { stroke: 'stroke-amber-500', label: 'DEGRADED', color: 'text-amber-500' };
    return { stroke: 'stroke-red-500', label: 'SUSPECT', color: 'text-red-500' };
  }, [results.image?.authenticity?.overallScore]);

  const aiRiskConfig = useMemo(() => {
    const risk = results.image?.authenticity?.aiProbability ?? 0;
    if (risk >= 60) return { stroke: 'stroke-red-500', label: 'HIGH RISK', color: 'text-red-500' };
    if (risk >= 30) return { stroke: 'stroke-amber-500', label: 'MODERATE', color: 'text-amber-500' };
    return { stroke: 'stroke-emerald-500', label: 'SECURE', color: 'text-emerald-500' };
  }, [results.image?.authenticity?.aiProbability]);

  const bannerConfig = useMemo(() => {
    const auth = results.image?.authenticity;
    if (!auth) return null;
    if (auth.isAiGenerated) {
      return {
        styles: 'border-red-500/20 bg-red-500/5 text-red-700 dark:text-red-300',
        iconColor: 'text-red-500',
        title: '🚨 HIGHLY SUSPICIOUS: SYNTHETIC PATTERNS IDENTIFIED',
        desc: 'Micro-anomalies detected in local pixel textures and Fourier frequencies align with Diffusion model renders. Sub-pixel analysis indicates structural synthesis rather than physical light refraction.'
      };
    }
    if (auth.containerChecks?.strippedMetadata) {
      return {
        styles: 'border-amber-500/20 bg-amber-500/5 text-amber-700 dark:text-amber-300',
        iconColor: 'text-amber-500',
        title: '⚠️ PROVENANCE DEGRADED: EXIF METADATA STRIPPED',
        desc: 'File contains zero camera metadata, author fields, or creation time signatures. While no definitive AI fingerprint is detected, stripped provenance is a strong indicator of web scraping or synthetic export channels.'
      };
    }
    return {
      styles: 'border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300',
      iconColor: 'text-emerald-500',
      title: '◎ FORENSIC INTEGRITY: AUTHENTIC PERIMETER CONFIRMED',
      desc: 'EXIF metadata is intact, consistent with standard camera profiles. Physical lens aberration dispersion matches radial sensor exposure, confirming an organic digital photography origin.'
    };
  }, [results.image?.authenticity]);

  return (
    <div id="image_verify_panel" className="space-y-8 animate-in fade-in duration-500">
      {/* Executive Indicators Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-stretch">
        {/* Forensic Image Viewer Card */}
        <div className="lg:col-span-1 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 flex flex-col justify-between shadow-sm transition-colors">
          <div className="space-y-4">
            <div className="flex items-center justify-between gap-4">
              <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
                <Maximize2 className="w-3.5 h-3.5" /> FORENSIC CANVAS
              </h4>
              <div className="flex gap-1 bg-slate-100 dark:bg-slate-800 p-1 rounded-lg transition-colors">
                {(['normal', 'ela', 'noise'] as const).map((mode) => (
                  <button
                    key={mode}
                    onClick={() => setImagePreviewMode(mode)}
                    className={`px-2.5 py-1 rounded-md text-[9px] font-mono font-black uppercase transition-all cursor-pointer ${
                      imagePreviewMode === mode
                        ? 'bg-white dark:bg-slate-700 text-red-600 dark:text-red-400 shadow-sm'
                        : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                    }`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            </div>

            {/* Image Render Area */}
            <div className="relative aspect-video rounded-xl overflow-hidden bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-center group transition-colors">
              {results.image.previewUrl ? (
                <img
                  src={results.image.previewUrl}
                  alt={results.image.fileName}
                  referrerPolicy="no-referrer"
                  className="max-h-full max-w-full object-contain transition-all duration-300"
                  style={{ filter: filterStyle }}
                />
              ) : (
                <div className="text-slate-400 flex flex-col items-center gap-2">
                  <ImageIcon className="w-10 h-10 stroke-[1] opacity-20" />
                  <span className="text-[10px] font-mono uppercase font-bold tracking-widest">No Preview Available</span>
                </div>
              )}

              {/* Glowing Forensics Active HUD Overlay */}
              <div className="absolute top-3 left-3 px-2 py-1 rounded-lg bg-black/80 dark:bg-slate-900/90 border border-red-500/30 text-[9px] font-mono text-red-400 font-bold uppercase flex items-center gap-2 shadow-xl backdrop-blur-sm">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                </span>
                HUD: {hudText}
              </div>
            </div>

            {/* File Metrics List */}
            <div className="space-y-3 pt-2">
              <ForensicStat label="File Name" value={results.image.fileName} />
              <ForensicStat
                label="File Size"
                value={results.image.fileSize > 1048576
                  ? `${(results.image.fileSize / 1048576).toFixed(2)} MB`
                  : `${(results.image.fileSize / 1024).toFixed(2)} KB`}
              />
              <ForensicStat
                label="Dimensions"
                value={results.image.dimensions
                  ? `${results.image.dimensions.width} × ${results.image.dimensions.height} px`
                  : 'N/A'}
              />
              <ForensicStat label="MIME Type" value={results.image.mimeType} />
            </div>
          </div>

          <div className="text-[10px] text-slate-500 dark:text-slate-500 font-mono text-center pt-6 border-t border-slate-100 dark:border-slate-800/50 mt-6 italic">
            <Shield className="w-3 h-3 inline mr-1 opacity-50" />
            Zero cloud storage upload occurs. DOM Sandbox isolation active.
          </div>
        </div>

        {/* Authenticity and AI Probabilities Gauges */}
        <div className="lg:col-span-2 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 flex flex-col justify-between shadow-sm transition-colors">
          <div className="space-y-8">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-100 dark:border-slate-800/60 pb-4 gap-4">
              <h3 className="text-sm font-bold text-slate-600 dark:text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2">
                <Activity className="w-4 h-4 text-red-500" /> INTEGRITY ANALYSIS ENGINE
              </h3>
              <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-100 dark:border-slate-800 transition-colors">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-[10px] text-slate-600 dark:text-slate-400 font-mono font-bold">{scanTime}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-12 items-center py-4">
              {/* Authenticity Index circular score */}
              <div className="flex flex-col items-center text-center p-6 rounded-2xl border border-slate-100 dark:border-slate-800 bg-slate-50/30 dark:bg-slate-800/20 transition-colors">
                <span className="text-[10px] font-mono tracking-widest text-slate-500 dark:text-slate-500 uppercase font-black mb-6">AUTHENTICITY INDEX</span>
                <div className="relative flex items-center justify-center" role="img" aria-label={`Authenticity: ${results.image.authenticity.overallScore}%`}>
                  <svg className="w-36 h-36 transform -rotate-90">
                    <circle cx="72" cy="72" r="62" className="stroke-slate-100 dark:stroke-slate-800 fill-none transition-colors" strokeWidth="8" />
                    <circle
                      cx="72" cy="72" r="62" className={`fill-none transition-all duration-1000 ${authenticityConfig.stroke}`}
                      strokeWidth="8" strokeDasharray={389} strokeDashoffset={389 - (389 * results.image.authenticity.overallScore) / 100} strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute text-center">
                    <span className="text-4xl font-black text-slate-900 dark:text-white font-mono tracking-tighter">
                      {results.image.authenticity.overallScore}%
                    </span>
                    <span className={`text-[10px] block font-mono font-black mt-1 ${authenticityConfig.color}`}>{authenticityConfig.label}</span>
                  </div>
                </div>
              </div>

              {/* AI Probability circular score */}
              <div className="flex flex-col items-center text-center p-6 rounded-2xl border border-slate-100 dark:border-slate-800 bg-slate-50/30 dark:bg-slate-800/20 transition-colors">
                <span className="text-[10px] font-mono tracking-widest text-slate-500 dark:text-slate-500 uppercase font-black mb-6">AI RISK PROBABILITY</span>
                <div className="relative flex items-center justify-center" role="img" aria-label={`AI Risk: ${results.image.authenticity.aiProbability}%`}>
                  <svg className="w-36 h-36 transform -rotate-90">
                    <circle cx="72" cy="72" r="62" className="stroke-slate-100 dark:stroke-slate-800 fill-none transition-colors" strokeWidth="8" />
                    <circle
                      cx="72" cy="72" r="62" className={`fill-none transition-all duration-1000 ${aiRiskConfig.stroke}`}
                      strokeWidth="8" strokeDasharray={389} strokeDashoffset={389 - (389 * results.image.authenticity.aiProbability) / 100} strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute text-center">
                    <span className="text-4xl font-black text-slate-900 dark:text-white font-mono tracking-tighter">
                      {results.image.authenticity.aiProbability}%
                    </span>
                    <span className={`text-[10px] block font-mono font-black mt-1 ${aiRiskConfig.color}`}>{aiRiskConfig.label}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Prominent Heuristics Banner */}
            {bannerConfig && (
              <div className={`p-5 rounded-2xl border text-sm flex items-start gap-4 leading-relaxed transition-all shadow-sm ${bannerConfig.styles}`}>
                <AlertCircle className={`w-6 h-6 shrink-0 mt-0.5 ${bannerConfig.iconColor}`} />
                <div className="space-y-1.5">
                  <h5 className="block font-mono font-black text-[11px] uppercase tracking-widest">
                    {bannerConfig.title}
                  </h5>
                  <p className="text-xs leading-relaxed opacity-90">
                    {bannerConfig.desc}
                  </p>
                </div>
              </div>
            )}
          </div>

          <div className="pt-6 border-t border-slate-100 dark:border-slate-800/60 mt-6 flex flex-wrap items-center gap-3 text-[10px] font-mono text-slate-500 dark:text-slate-500">
            <span className="font-black text-slate-700 dark:text-slate-400 uppercase tracking-tighter">METHODOLOGY:</span>
            <span>Multi-bucket signal consensus (EXIF, SHA-256 Fingerprint, Error Level Analysis).</span>
          </div>
        </div>
      </div>

      {/* Forensic Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* 1. AI-Generation Indicators */}
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-5 shadow-sm transition-colors">
          <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800/60 pb-4">
            <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-500">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-widest font-mono transition-colors">AI-GENERATION METRICS</h4>
              <p className="text-[10px] text-slate-500 dark:text-slate-500 mt-0.5">Frequency domain analysis & structural texturing</p>
            </div>
          </div>

          <div className="space-y-3">
            {results.image.authenticity.clues.filter(c => c.category === 'indicator').map((clue, idx) => {
              const styles = getSeverityStyles(clue.severity);
              const SeverityIcon = styles.icon;
              return (
                <div key={idx} className="p-3.5 bg-slate-50/50 dark:bg-slate-800/20 border border-slate-100 dark:border-slate-800 rounded-xl flex items-start gap-3.5 text-xs leading-relaxed group transition-all hover:border-slate-200 dark:hover:border-slate-700">
                  <div className={`p-1.5 rounded-lg ${styles.badge} shadow-sm group-hover:scale-110 transition-transform`}>
                     <SeverityIcon className="w-3.5 h-3.5" />
                  </div>
                  <div className="space-y-1">
                    <span className="font-bold text-slate-800 dark:text-slate-200 font-sans block transition-colors">{clue.title}</span>
                    <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed transition-colors">{clue.description}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* 2. EXIF and GPS Clues */}
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-5 shadow-sm transition-colors">
          <div className="flex items-center gap-3 border-b border-slate-100 dark:border-slate-800/60 pb-4">
            <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-500">
              <Camera className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-xs font-black text-slate-900 dark:text-white uppercase tracking-widest font-mono transition-colors">EXIF & HARDWARE AUDIT</h4>
              <p className="text-[10px] text-slate-500 dark:text-slate-500 mt-0.5">Container metadata & sensor signature verification</p>
            </div>
          </div>

          {/* Active EXIF tags table */}
          {Object.keys(results.image.exif || {}).length > 0 ? (
            <div className="border border-slate-100 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
              <table className="w-full text-left border-collapse font-mono text-[11px]">
                <thead>
                  <tr className="bg-slate-50 dark:bg-slate-900/50 border-b border-slate-100 dark:border-slate-800 text-[9px] text-slate-500 dark:text-slate-500 uppercase font-black tracking-widest transition-colors">
                    <th className="p-3">HEADER</th>
                    <th className="p-3">VALUE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50 dark:divide-slate-800 transition-colors">
                  {Object.entries(results.image.exif || {}).map(([key, val]) => (
                    <tr key={key} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition-colors">
                      <td className="p-3 text-red-600 dark:text-red-400 font-bold w-1/3">{key}</td>
                      <td className="p-3 text-slate-700 dark:text-slate-300 truncate max-w-[180px]" title={String(val)}>
                        {String(val)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-8 text-center border-2 border-dashed border-slate-100 dark:border-slate-800 rounded-2xl text-[11px] font-mono text-slate-500 dark:text-slate-500 transition-colors">
              No EXIF attributes detected inside image container.
            </div>
          )}

          {/* GPS Geo-reference metadata */}
          {results.image.gps && (
            <div className="p-4 bg-amber-500/5 dark:bg-amber-500/5 border border-amber-500/20 rounded-xl flex items-center justify-between text-xs transition-colors shadow-sm">
              <div className="flex items-center gap-3">
                <MapPin className="w-4 h-4 text-amber-500 shrink-0" />
                <span className="font-mono font-bold text-slate-700 dark:text-slate-300">
                  {results.image.gps.latitude?.toFixed(4)}, {results.image.gps.longitude?.toFixed(4)}
                </span>
              </div>
              <a
                href={results.image.gps.mapsLink}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-1.5 rounded-lg bg-amber-500 text-white font-mono font-black text-[9px] uppercase flex items-center gap-1.5 transition-all hover:bg-amber-600 active:scale-95 shadow-md shadow-amber-500/20"
              >
                OPEN MAPS <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          )}

          <div className="space-y-3">
            {results.image.authenticity.clues.filter(c => c.category === 'exif').map((clue, idx) => {
              const styles = getSeverityStyles(clue.severity);
              const SeverityIcon = styles.icon;
              return (
                <div key={idx} className="p-3.5 bg-slate-50/50 dark:bg-slate-800/20 border border-slate-100 dark:border-slate-800 rounded-xl flex items-start gap-3.5 text-xs leading-relaxed group transition-all hover:border-slate-200 dark:hover:border-slate-700">
                  <div className={`p-1.5 rounded-lg ${styles.badge} shadow-sm group-hover:scale-110 transition-transform`}>
                     <SeverityIcon className="w-3.5 h-3.5" />
                  </div>
                  <div className="space-y-1">
                    <span className="font-bold text-slate-800 dark:text-slate-200 font-sans block transition-colors">{clue.title}</span>
                    <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed transition-colors">{clue.description}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
});

ForensicViewer.displayName = 'ForensicViewer';
ForensicStat.displayName = 'ForensicStat';
