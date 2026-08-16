/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { Gauge, RefreshCw, FileText } from 'lucide-react';
import { ScanResults, SpeedTestResult } from '../../types';
import { scanSpeedTest } from '../../services/osintServices';
import { makeSpeedTestResults } from '../../utils/resultBuilders';

interface SpeedTestWorkspaceProps {
  isLightMode: boolean;
  isScanning: boolean;
  results: ScanResults | null;
  onScanComplete: (results: ScanResults) => void;
  showToast: (message: string, type?: 'success' | 'info' | 'error') => void;
}

export default function SpeedTestWorkspace({
  isLightMode,
  isScanning,
  results,
  onScanComplete,
  showToast,
}: SpeedTestWorkspaceProps) {
  const isDarkMode = !isLightMode;
  const handleRun = async () => {
    try {
      const result = await scanSpeedTest();
      onScanComplete(makeSpeedTestResults(result));
    } catch (e) {
      showToast('Speed test failed. Please try again.', 'error');
    }
  };

  if (isScanning) {
    return (
      <div className="flex items-center justify-center gap-3 py-10">
        <RefreshCw className="w-6 h-6 animate-spin text-emerald-500" />
        <span className="text-sm font-mono font-bold" style={{ color: 'var(--text-primary)' }}>Measuring bandwidth and latency...</span>
      </div>
    );
  }

  if (results?.speedtest) {
    return (
      <div className="space-y-4 sm:space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
          <div className="p-4 sm:p-5 rounded-xl border"
            style={{
              borderColor: 'var(--color-pass-border)',
              background: 'var(--color-pass-bg)',
            }}>
            <div className="text-[10px] font-mono uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Cloudflare Edge</div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-black font-mono" style={{ color: 'var(--text-primary)' }}>{results.speedtest.cloudflare.downloadMbps}</span>
              <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Mbps ↓</span>
            </div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-sm font-mono font-bold" style={{ color: 'var(--text-secondary)' }}>{results.speedtest.cloudflare.uploadMbps}</span>
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>Mbps ↑</span>
            </div>
            <div className="text-[10px] font-mono mt-2" style={{ color: 'var(--text-muted)' }}>{results.speedtest.cloudflare.node}</div>
          </div>
          <div className="p-4 sm:p-5 rounded-xl border"
            style={{
              borderColor: 'var(--color-pass-border)',
              background: 'var(--color-pass-bg)',
            }}>
            <div className="text-[10px] font-mono uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>M-Lab (MSAK)</div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-black font-mono" style={{ color: 'var(--text-primary)' }}>{results.speedtest.mlab.downloadMbps}</span>
              <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>Mbps ↓</span>
            </div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-sm font-mono font-bold" style={{ color: 'var(--text-secondary)' }}>{results.speedtest.mlab.uploadMbps}</span>
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>Mbps ↑</span>
            </div>
            <div className="text-[10px] font-mono mt-2" style={{ color: 'var(--text-muted)' }}>{results.speedtest.mlab.node}</div>
          </div>
        </div>

        <div className="border rounded-lg overflow-hidden" style={{ borderColor: 'var(--border-default)' }}>
          <table className="w-full text-left border-collapse font-mono text-[11px]">
            <thead className="text-[10px]" style={{
              background: 'var(--bg-muted)',
              color: 'var(--text-secondary)',
            }}>
              <tr>
                <th className="px-3 py-2 font-bold">Region</th>
                <th className="px-3 py-2 font-bold">Latency</th>
              </tr>
            </thead>
            <tbody style={{ borderColor: 'var(--border-subtle)' }} className="divide-y" >
              {results.speedtest.latency.map((n, idx) => (
                <tr key={idx}>
                  <td className="px-3 py-2" style={{ color: 'var(--text-primary)' }}>{n.flag} {n.name}</td>
                  <td className="px-3 py-2" style={{
                    color: n.latencyMs > 400 ? 'var(--color-critical)' : n.latencyMs > 300 ? 'var(--color-high)' : 'var(--color-pass)',
                  }}>{n.latencyMs} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="p-3 rounded-lg border text-[11px] font-mono" style={{
          borderColor: 'var(--border-default)',
          background: 'var(--bg-muted)',
        }}>
          <div style={{ color: 'var(--text-muted)' }}>Outgoing IP: <span className="font-bold" style={{ color: 'var(--text-primary)' }}>{results.speedtest.outgoingIp}</span> · {results.speedtest.ipVersion}</div>
          <p className="text-slate-400 mt-1 leading-relaxed">{results.speedtest.note}</p>
        </div>

        <button
          type="button"
          onClick={handleRun}
          className="w-full py-3 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 hover:opacity-90"
          style={{
            background: 'var(--color-pass)',
            color: 'var(--text-on-accent)',
          }}
        >
          <RefreshCw className="w-4 h-4" /> Run Again
        </button>
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={handleRun}
      className="w-full py-3.5 rounded-xl text-sm font-bold transition-all cursor-pointer flex items-center justify-center gap-2 hover:opacity-90"
      style={{
        background: 'var(--color-pass)',
        color: 'var(--text-on-accent)',
      }}
    >
      <span className="flex items-center gap-2">
        <Gauge className="w-4 h-4" /> Run Speed Test
      </span>
    </button>
  );
}
