/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo, memo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  Info,
  Clock,
  FileCheck,
  Eye,
  CheckCircle2
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';
import { ScanResults } from '../../types';

interface OverviewTabProps {
  results: ScanResults;
  scoreDetails: {
    grade: string;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  scoreHistoryData: Array<{ date: string; score: number }>;
  setActiveTab: (tab: string) => void;
}

const RiskGauge = memo(({ riskScore, grade }: { riskScore: number; grade: string }) => {
  const securityGrade = 100 - riskScore;
  const strokeColor = useMemo(() => {
    if (riskScore > 65) return '#dc2626'; // Red-600
    if (riskScore > 35) return '#d97706'; // Amber-600
    return '#16a34a'; // Green-600
  }, [riskScore]);

  const dashArray = 465;
  const dashOffset = useMemo(() =>
    dashArray - (dashArray * securityGrade) / 100
  , [securityGrade]);

  return (
    <div className="lg:col-span-1 rounded-2xl p-6 flex flex-col items-center justify-between min-h-[360px] bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm transition-colors">
      <div className="w-full text-left">
        <h3 className="text-sm font-bold tracking-wider uppercase font-mono text-slate-600 dark:text-slate-400">RISK SCORE GAUGE</h3>
        <p className="text-xs mt-1 text-slate-500 dark:text-slate-500">Calculated via deterministic rule severity aggregation</p>
      </div>

      <div className="relative flex items-center justify-center my-6" role="img" aria-label={`Security grade: ${securityGrade}%`}>
        <svg className="w-44 h-44 transform -rotate-90" viewBox="0 0 176 176">
          <circle
            cx="88"
            cy="88"
            r="74"
            fill="none"
            className="stroke-slate-100 dark:stroke-slate-800"
            strokeWidth="12"
          />
          <circle
            cx="88"
            cy="88"
            r="74"
            className="fill-none transition-all duration-1000"
            stroke={strokeColor}
            strokeWidth="12"
            strokeDasharray={dashArray}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute text-center">
          <span className="text-5xl font-black font-mono tracking-tighter text-slate-900 dark:text-white">
            {securityGrade}
          </span>
          <span className="block font-mono text-xs font-bold mt-1 text-slate-500 dark:text-slate-400">SECURITY GRADE</span>
        </div>
      </div>

      <div className="w-full grid grid-cols-2 gap-4 pt-4 border-t border-slate-100 dark:border-slate-800 text-center">
        <div>
          <span className="text-[10px] font-mono font-bold uppercase block mb-1 text-slate-500 dark:text-slate-400">RISK ASSESSMENT</span>
          <span
            className="text-sm font-bold font-mono"
            style={{ color: strokeColor }}
          >
            {riskScore > 65 ? 'CRITICAL RISK' : riskScore > 35 ? 'MODERATE RISK' : 'SECURE'}
          </span>
        </div>
        <div>
          <span className="text-[10px] font-mono font-bold uppercase block mb-1 text-slate-500 dark:text-slate-400">SECURITY LEVEL</span>
          <span className="text-sm font-bold font-mono text-slate-900 dark:text-white">
            {grade}
          </span>
        </div>
      </div>
    </div>
  );
});

const FindingStat = memo(({ label, count, colorClass, bgClass, borderClass, textClass }: any) => (
  <div
    className={`rounded-xl p-4 flex flex-col items-center justify-center border ${bgClass} ${borderClass} transition-colors`}
  >
    <span className={`text-[10px] font-mono font-bold tracking-wider ${textClass}`}>{label}</span>
    <span className={`text-4xl font-black font-mono mt-1 ${colorClass}`}>{count}</span>
  </div>
));

const ExecutiveSummary = memo(({ target, scoreDetails, setActiveTab }: any) => {
  const { grade, criticalCount, highCount, mediumCount } = scoreDetails;

  const statusContent = useMemo(() => {
    if (criticalCount > 0 || highCount > 0) {
      return (
        <div className="text-red-800 dark:text-red-200 bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-900/30 p-3 rounded-xl transition-colors">
          <p className="text-sm">
            <strong>Immediate Intervention Required:</strong> The presence of {criticalCount} critical and {highCount} high-risk vulnerabilities compromises the perimeter integrity. Unauthenticated spoofing, downgrade exploits, or unencrypted session tracking may be viable threat scenarios.
          </p>
        </div>
      );
    }
    if (mediumCount > 0) {
      return (
        <div className="text-amber-800 dark:text-amber-200 bg-amber-50 dark:bg-amber-900/20 border border-amber-100 dark:border-amber-900/30 p-3 rounded-xl transition-colors">
          <p className="text-sm">
            <strong>Advisory Action Recommended:</strong> The investigation flagged {mediumCount} moderate anomalies. Hardening server configuration values (like HTTP security headers) and aligning SPF/DMARC policies are advised to reduce overall risk posture.
          </p>
        </div>
      );
    }
    return (
      <div className="text-emerald-800 dark:text-emerald-200 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-900/30 p-3 rounded-xl transition-colors">
        <p className="text-sm">
          <strong>Excellent Security Hygiene:</strong> Our evaluation identified zero critical or medium-risk anomalies. Standard security configurations are properly synchronized, showing outstanding posture.
        </p>
      </div>
    );
  }, [criticalCount, highCount, mediumCount]);

  return (
    <div className="rounded-2xl p-6 flex-1 flex flex-col justify-between bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm transition-colors">
      <div>
        <h3 className="text-sm font-bold tracking-wider uppercase font-mono flex items-center gap-2 text-slate-600 dark:text-slate-400">
          <FileCheck className="w-4 h-4 text-red-500" /> EXECUTIVE INTELLIGENCE SUMMARY
        </h3>
        <div className="text-sm leading-relaxed space-y-4 mt-4 text-slate-700 dark:text-slate-300">
          <p>
            Our deterministic OSINT analysis of the endpoint <code className="px-1.5 py-0.5 rounded font-mono text-xs bg-slate-100 dark:bg-slate-800 text-red-600 dark:text-red-400 border border-slate-200 dark:border-slate-700 transition-colors">{target.value}</code> has concluded with a security grade of <strong className="font-mono text-base text-slate-900 dark:text-white">{grade}</strong>.
          </p>
          {statusContent}
          <p className="text-xs text-slate-500 dark:text-slate-500">
            This summary is structured through automated client-side rules evaluating raw network signatures. No personal identifiers or data logs have left the browser.
          </p>
        </div>
      </div>

      <div className="pt-4 mt-6 border-t border-slate-100 dark:border-slate-800 flex flex-wrap gap-3">
        <button
          onClick={() => setActiveTab('evidence')}
          className="px-4 py-2 text-xs rounded-lg bg-red-600 hover:bg-red-700 text-white font-medium transition-all flex items-center gap-1.5 cursor-pointer shadow-sm active:transform active:scale-95"
          aria-label="View detailed findings"
        >
          <Eye className="w-3.5 h-3.5" /> View Findings
        </button>
        <button
          onClick={() => setActiveTab('recommendations')}
          className="px-4 py-2 text-xs rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium transition-all flex items-center gap-1.5 cursor-pointer active:transform active:scale-95"
          aria-label="View remediation action plan"
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-red-500" /> Remediation Plan
        </button>
      </div>
    </div>
  );
});

const HistoricalAudit = memo(({ scoreHistoryData, target, riskScore }: any) => {
  return (
    <div className="mt-8 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 transition-colors shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-sm font-bold text-slate-600 dark:text-slate-400 tracking-wider uppercase font-mono flex items-center gap-2">
            <Clock className="w-4 h-4 text-red-500" /> HISTORICAL RISK TREND AUDIT
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">Tracks security score evolution over successive system audits</p>
        </div>
        <div className="text-right">
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20 uppercase font-bold transition-colors">
            Active Target: {target.value}
          </span>
        </div>
      </div>

      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={scoreHistoryData}
            margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
          >
            <defs>
              <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#dc2626" stopOpacity={0.0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="currentColor" className="text-slate-200 dark:text-slate-800" vertical={false} />
            <XAxis
              dataKey="date"
              stroke="currentColor"
              className="text-slate-400 dark:text-slate-600"
              fontSize={10}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              domain={[0, 100]}
              stroke="currentColor"
              className="text-slate-400 dark:text-slate-600"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => `${v}%`}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0f172a',
                borderColor: '#1e293b',
                color: '#f8fafc',
                borderRadius: '8px',
                fontSize: '11px',
                fontFamily: 'monospace',
                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
              }}
              itemStyle={{ color: '#ef4444' }}
              labelStyle={{ color: '#94a3b8', fontWeight: 'bold', marginBottom: '4px' }}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke="#dc2626"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorScore)"
              animationDuration={1500}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-4 flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-500 font-mono">
        <span>← EARLIER RUNS</span>
        <span>CURRENT POSTURE: {riskScore}% RISK SCORE</span>
      </div>
    </div>
  );
});

export const OverviewTab: React.FC<OverviewTabProps> = memo(({
  results,
  scoreDetails,
  scoreHistoryData,
  setActiveTab,
}) => {
  const { target, riskScore } = results;

  const stats = useMemo(() => [
    {
      label: 'CRITICAL',
      count: scoreDetails.criticalCount,
      colorClass: 'text-red-600 dark:text-red-500',
      bgClass: 'bg-red-50/50 dark:bg-red-950/20',
      borderClass: 'border-red-100 dark:border-red-900/30',
      textClass: 'text-red-800 dark:text-red-400'
    },
    {
      label: 'HIGH',
      count: scoreDetails.highCount,
      colorClass: 'text-orange-600 dark:text-orange-500',
      bgClass: 'bg-orange-50/50 dark:bg-orange-950/20',
      borderClass: 'border-orange-100 dark:border-orange-900/30',
      textClass: 'text-orange-800 dark:text-orange-400'
    },
    {
      label: 'MEDIUM',
      count: scoreDetails.mediumCount,
      colorClass: 'text-amber-600 dark:text-amber-500',
      bgClass: 'bg-amber-50/50 dark:bg-amber-950/20',
      borderClass: 'border-amber-100 dark:border-amber-900/30',
      textClass: 'text-amber-800 dark:text-amber-400'
    },
    {
      label: 'LOW',
      count: scoreDetails.lowCount,
      colorClass: 'text-blue-600 dark:text-blue-500',
      bgClass: 'bg-blue-50/50 dark:bg-blue-950/20',
      borderClass: 'border-blue-100 dark:border-blue-900/30',
      textClass: 'text-blue-800 dark:text-blue-400'
    },
  ], [scoreDetails]);

  return (
    <div id="overview_panel" className="animate-in fade-in duration-500">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <RiskGauge riskScore={riskScore} grade={scoreDetails.grade} />

        <div className="lg:col-span-2 flex flex-col gap-8">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {stats.map((stat) => (
              <FindingStat key={stat.label} {...stat} />
            ))}
          </div>

          <ExecutiveSummary
            target={target}
            scoreDetails={scoreDetails}
            setActiveTab={setActiveTab}
          />
        </div>
      </div>

      <HistoricalAudit
        scoreHistoryData={scoreHistoryData}
        target={target}
        riskScore={riskScore}
      />
    </div>
  );
});

OverviewTab.displayName = 'OverviewTab';
RiskGauge.displayName = 'RiskGauge';
FindingStat.displayName = 'FindingStat';
ExecutiveSummary.displayName = 'ExecutiveSummary';
HistoricalAudit.displayName = 'HistoricalAudit';
