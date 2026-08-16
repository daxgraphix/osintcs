/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  getAllModules,
  getModule,
  getModulesByCategory,
  isModuleTab,
  getModuleTabOrder,
} from '../components/pages/moduleRegistry';

describe('module registry integration', () => {
  it('returns the canonical module metadata for known tabs', () => {
    const domain = getModule('domain');
    expect(domain?.label).toBe('Domain DNS');
    expect(domain?.placeholder).toContain('example.com');
  });

  it('groups modules by category in a stable order', () => {
    const infrastructure = getModulesByCategory('Infrastructure');
    expect(infrastructure[0]?.id).toBe('domain');
    expect(infrastructure.some((module) => module.id === 'website')).toBe(true);
  });

  it('supports module-tab detection and ordered navigation', () => {
    expect(isModuleTab('risk')).toBe(true);
    expect(isModuleTab('home')).toBe(false);
    expect(isModuleTab('unknown')).toBe(false);
    expect(getModuleTabOrder()[0]).toBe('risk');
  });

  it('exposes a full registry without duplication', () => {
    const modules = getAllModules();
    const ids = modules.map((module) => module.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
