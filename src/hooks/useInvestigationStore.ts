
import { useState, useCallback, useEffect } from 'react';
import { ScanResults } from '../types';

/**
 * A simple hook-based store to manage scan history and state.
 * This can be later migrated to Zustand or IndexedDB.
 */
export function useInvestigationStore(targetValue?: string) {
  const [flaggedFindings, setFlaggedFindings] = useState<Record<string, 'critical' | 'interesting' | null>>({});

  useEffect(() => {
    if (!targetValue) return;
    try {
      const stored = localStorage.getItem(`osintcs_flagged_${targetValue}`);
      if (stored) {
        setFlaggedFindings(JSON.parse(stored));
      } else {
        setFlaggedFindings({});
      }
    } catch (e) {
      console.error('Failed to load flagged findings:', e);
    }
  }, [targetValue]);

  const toggleFlagFinding = useCallback((findingId: string, flag: 'critical' | 'interesting') => {
    if (!targetValue) return;
    setFlaggedFindings((prev) => {
      const current = prev[findingId];
      const nextValue = current === flag ? null : flag;
      const updated = { ...prev, [findingId]: nextValue };
      try {
        localStorage.setItem(`osintcs_flagged_${targetValue}`, JSON.stringify(updated));
      } catch (e) {
        console.error('Failed to save flagged findings:', e);
      }
      return updated;
    });
  }, [targetValue]);

  return {
    flaggedFindings,
    toggleFlagFinding,
  };
}
