/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { TargetType } from '../../types';
import { ModuleConfig, QUICK_MODULES } from './moduleConfig';

const REGISTRY = new Map<TargetType | 'risk', ModuleConfig>();

for (const mod of QUICK_MODULES) {
  REGISTRY.set(mod.id, mod);
}

export function getModule(id: TargetType | 'risk'): ModuleConfig | undefined {
  return REGISTRY.get(id);
}

export function getAllModules(): ModuleConfig[] {
  return QUICK_MODULES;
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
