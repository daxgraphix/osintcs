/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

const STORAGE_KEY = 'osintcs_telemetry';
const MAX_EVENTS = 200;

type TelemetryEvent = {
  id: string;
  timestamp: number;
  type: 'module_used' | 'scan_completed' | 'scan_failed' | 'exported' | 'error';
  module?: string;
  targetType?: string;
  durationMs?: number;
  error?: string;
  meta?: Record<string, unknown>;
};

function isEnabled(): boolean {
  try {
    return localStorage.getItem('osintcs_telemetry_enabled') === 'true';
  } catch {
    return false;
  }
}

function getEvents(): TelemetryEvent[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function persist(events: TelemetryEvent[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(events.slice(-MAX_EVENTS)));
  } catch {
    // storage full or unavailable
  }
}

export function enableTelemetry() {
  try {
    localStorage.setItem('osintcs_telemetry_enabled', 'true');
  } catch {}
}

export function disableTelemetry() {
  try {
    localStorage.removeItem('osintcs_telemetry_enabled');
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
}

export function recordEvent(event: Omit<TelemetryEvent, 'id' | 'timestamp'>) {
  if (!isEnabled()) return;
  const events = getEvents();
  events.push({
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    ...event,
  });
  persist(events);
}

export function getTelemetrySummary() {
  const events = getEvents();
  const moduleCounts: Record<string, number> = {};
  const errorCounts: Record<string, number> = {};
  let totalScans = 0;
  let failedScans = 0;
  let totalDurationMs = 0;
  let durationSamples = 0;

  for (const evt of events) {
    if (evt.type === 'module_used' && evt.module) {
      moduleCounts[evt.module] = (moduleCounts[evt.module] || 0) + 1;
    }
    if (evt.type === 'scan_completed') {
      totalScans++;
      if (typeof evt.durationMs === 'number') {
        totalDurationMs += evt.durationMs;
        durationSamples++;
      }
    }
    if (evt.type === 'scan_failed') {
      failedScans++;
      if (evt.module) {
        errorCounts[evt.module] = (errorCounts[evt.module] || 0) + 1;
      }
    }
    if (evt.type === 'error' && evt.error) {
      errorCounts[evt.error] = (errorCounts[evt.error] || 0) + 1;
    }
  }

  return {
    enabled: isEnabled(),
    totalEvents: events.length,
    moduleCounts,
    totalScans,
    failedScans,
    averageDurationMs: durationSamples ? Math.round(totalDurationMs / durationSamples) : 0,
    errorCounts,
  };
}
