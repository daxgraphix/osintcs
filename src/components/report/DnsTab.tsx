/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { memo, useMemo } from 'react';
import { Mail, Shield, Lock, Copy, Check, Globe, Server, Hash } from 'lucide-react';
import { DNSResult } from '../../types';

interface DnsTabProps {
  dns: DNSResult;
  copiedText: string | null;
  handleCopy: (text: string, id: string) => void;
}

const StatusCard = memo(({
  icon: Icon,
  label,
  isPresent,
  presentLabel = 'PRESENT',
  missingLabel = 'MISSING',
  warning = false
}: {
  icon: any;
  label: string;
  isPresent: boolean;
  presentLabel?: string;
  missingLabel?: string;
  warning?: boolean;
}) => (
  <div className="p-3.5 rounded-lg bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 flex items-center justify-between transition-colors">
    <div className="flex items-center gap-2.5">
      <Icon className={`w-4 h-4 ${
        isPresent ? 'text-emerald-500' : warning ? 'text-amber-500' : 'text-red-500'
      }`} />
      <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{label}</span>
    </div>
    <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
      isPresent
        ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
        : warning
          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
          : 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20'
    }`}>
      {isPresent ? presentLabel : missingLabel}
    </span>
  </div>
));

const RawRecordBox = memo(({
  title,
  record,
  copyId,
  handleCopy,
  isCopied
}: {
  title: string;
  record: string;
  copyId: string;
  handleCopy: any;
  isCopied: boolean;
}) => (
  <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-xl p-5 space-y-2 transition-colors">
    <div className="flex items-center justify-between">
      <span className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase">{title}</span>
      <button
        onClick={() => handleCopy(record, copyId)}
        className="p-1 rounded text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all cursor-pointer"
        aria-label={`Copy ${title}`}
      >
        {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    </div>
    <code className="text-[10px] font-mono p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200/80 dark:border-slate-800/80 block break-all text-red-600 dark:text-red-400 transition-colors">
      {record}
    </code>
  </div>
));

const ZoneEntry = memo(({
  type,
  records,
  handleCopy,
  copiedText
}: {
  type: string;
  records: string[];
  handleCopy: any;
  copiedText: string | null;
}) => (
  <div className="border border-slate-200/60 dark:border-slate-800/60 rounded-lg overflow-hidden bg-slate-50/10 dark:bg-slate-900/10 transition-colors">
    <div className="bg-slate-50/60 dark:bg-slate-800/40 px-4 py-2 flex items-center justify-between border-b border-slate-200/60 dark:border-slate-800/60">
      <span className="text-xs font-mono font-black text-red-500 dark:text-red-400">{type} Record</span>
      <span className="text-[10px] font-mono text-slate-500 dark:text-slate-500">{records.length} entry/entries</span>
    </div>
    <div className="p-3 divide-y divide-slate-100 dark:divide-slate-800">
      {records.map((record, index) => (
        <div key={index} className="py-2 first:pt-0 last:pb-0 flex items-center justify-between gap-4">
          <span className="text-xs font-mono text-slate-700 dark:text-slate-300 break-all select-all">{record}</span>
          <button
            onClick={() => handleCopy(record, `${type}_${index}`)}
            className="p-1 rounded text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all cursor-pointer shrink-0"
            aria-label={`Copy ${type} record`}
          >
            {copiedText === `${type}_${index}` ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
          </button>
        </div>
      ))}
    </div>
  </div>
));

export const DnsTab: React.FC<DnsTabProps> = memo(({
  dns,
  copiedText,
  handleCopy,
}) => {
  const dnsRecords = useMemo(() =>
    Object.entries(dns.records).filter(([_, list]) => list && Array.isArray(list) && list.length > 0)
  , [dns.records]);

  return (
    <div id="dns_panel" className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-in fade-in duration-500">
      {/* Policy Badges & Stats */}
      <div className="lg:col-span-1 space-y-6">
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-4 shadow-sm transition-colors">
          <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase">SECURITY RECORD STATE</h4>
          <div className="space-y-3">
            <StatusCard
              icon={Mail}
              label="SPF Record"
              isPresent={dns.spf.present}
            />
            <StatusCard
              icon={Shield}
              label="DMARC Record"
              isPresent={dns.dmarc.present}
            />
            <StatusCard
              icon={Lock}
              label="DNSSEC Support"
              isPresent={dns.dnssec.enabled}
              presentLabel="ENABLED"
              missingLabel="DISABLED"
              warning={!dns.dnssec.enabled}
            />
          </div>
        </div>

        {dns.spf.record && (
          <RawRecordBox
            title="RAW SPF TXT"
            record={dns.spf.record}
            copyId="spf_rec"
            handleCopy={handleCopy}
            isCopied={copiedText === 'spf_rec'}
          />
        )}

        {dns.dmarc.record && (
          <RawRecordBox
            title="RAW DMARC TXT"
            record={dns.dmarc.record}
            copyId="dmarc_rec"
            handleCopy={handleCopy}
            isCopied={copiedText === 'dmarc_rec'}
          />
        )}

        {dns.mxDetails && dns.mxDetails.length > 0 && (
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-3 shadow-sm transition-colors">
            <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
              <Server className="w-3.5 h-3.5" /> MX PRIORITY MATRIX
            </h4>
            <div className="space-y-2">
              {dns.mxDetails.map((mx, idx) => (
                <div key={idx} className="flex items-center justify-between p-2.5 rounded bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 transition-colors">
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] font-mono font-bold text-red-600 dark:text-red-400 bg-red-500/10 px-2 py-0.5 rounded">P{mx.priority}</span>
                    <span className="text-xs font-mono text-slate-700 dark:text-slate-300 break-all">{mx.host}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {dns.nameservers && dns.nameservers.length > 0 && (
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-3 shadow-sm transition-colors">
            <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
              <Globe className="w-3.5 h-3.5" /> AUTHORITATIVE NAMESERVERS
            </h4>
            <div className="space-y-2">
              {dns.nameservers.map((ns, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 flex items-center justify-between transition-colors">
                  <span className="text-xs font-mono text-slate-700 dark:text-slate-300">{ns}</span>
                  <button
                    onClick={() => handleCopy(ns, `ns_${idx}`)}
                    className="p-1 rounded text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all cursor-pointer"
                    aria-label="Copy nameserver"
                  >
                    {copiedText === `ns_${idx}` ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {dns.soa && (
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-2 shadow-sm transition-colors">
            <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase">SOA RECORD</h4>
            <code className="text-[10px] font-mono p-2.5 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200/80 dark:border-slate-800/80 block break-all text-slate-700 dark:text-slate-300 transition-colors">
              {dns.soa}
            </code>
          </div>
        )}

        {dns.caa && dns.caa.length > 0 && (
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-3 shadow-sm transition-colors">
            <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase flex items-center gap-2">
              <Hash className="w-3.5 h-3.5" /> CAA RECORDS
            </h4>
            <div className="space-y-2">
              {dns.caa.map((caa, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-50/50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-800 transition-colors">
                  <span className="text-xs font-mono text-slate-700 dark:text-slate-300 break-all">{caa}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* DNS Records Tabular Stream */}
      <div className="lg:col-span-2 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-2xl p-6 space-y-6 shadow-sm transition-colors">
        <div>
          <h3 className="text-sm font-bold text-slate-600 dark:text-slate-400 tracking-wider font-mono uppercase">DNS ZONE ENTRIES</h3>
          <p className="text-xs text-slate-500 dark:text-slate-500 mt-1">Queried live using Cloudflare DNS-over-HTTPS infrastructure</p>
        </div>

        <div className="space-y-4">
          {dnsRecords.map(([type, recordsList]) => (
            <ZoneEntry
              key={type}
              type={type}
              records={recordsList as string[]}
              handleCopy={handleCopy}
              copiedText={copiedText}
            />
          ))}
        </div>
      </div>
    </div>
  );
});

DnsTab.displayName = 'DnsTab';
StatusCard.displayName = 'StatusCard';
RawRecordBox.displayName = 'RawRecordBox';
ZoneEntry.displayName = 'ZoneEntry';
