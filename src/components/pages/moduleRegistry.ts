/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { TargetType } from '../../types';
import { ModuleConfig, QUICK_MODULES } from './moduleConfig';

export type ModuleTabId = TargetType | 'risk' | 'home' | 'settings' | 'history';

export const SPECIAL_TABS = new Set(['home', 'settings', 'history']);
export const QUERY_EXCLUDED_TABS = new Set(['home', 'settings', 'history', 'risk', 'image', 'metadata']);

const REGISTRY = new Map<TargetType | 'risk', ModuleConfig>();

for (const mod of QUICK_MODULES) {
  REGISTRY.set(mod.id, mod);
}

export function getModule(id: string): ModuleConfig | undefined {
  if (typeof id !== 'string') return undefined;
  return REGISTRY.get(id as TargetType | 'risk');
}

export function getAllModules(): ModuleConfig[] {
  return QUICK_MODULES;
}

export function getModuleTabOrder(): Array<TargetType | 'risk'> {
  return QUICK_MODULES.map((module) => module.id);
}

export function isModuleTab(tab: string): boolean {
  return typeof tab === 'string' && REGISTRY.has(tab as TargetType | 'risk');
}

export function canResolveQueryFromTab(tab: string): boolean {
  return isModuleTab(tab) && !QUERY_EXCLUDED_TABS.has(tab);
}

export function getModulesByCategory(category: string): ModuleConfig[] {
  const categoryMap: Record<string, (TargetType | 'risk')[]> = {
    'Infrastructure': ['domain', 'website', 'subdomain', 'portscan', 'networkscan', 'urlfuzz', 'waf', 'vhosts'],
    'Technology & Geo Intelligence': ['techlookup', 'geolookup', 'speedtest', 'googlehacking'],
    'Identity & People': ['username', 'peoplehunter', 'email', 'domainfinder'],
    'Forensics & Files': ['image', 'metadata', 'hash', 'poplenscan'],
    'System': ['risk', 'ip', 'ipadvance', 'myip'],
  };

  const ids = categoryMap[category] || [];
  return ids.map(id => REGISTRY.get(id)).filter((m): m is ModuleConfig => m !== undefined);
}
