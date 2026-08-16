
import { useEffect, useRef, useCallback, useState } from 'react';
import { ScanResults, Finding, Recommendation } from '../types';

export function useOsintWorker() {
  const workerRef = useRef<Worker | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  useEffect(() => {
    workerRef.current = new Worker(new URL('../workers/osint.worker.ts', import.meta.url), {
      type: 'module'
    });

    return () => {
      workerRef.current?.terminate();
    };
  }, []);

  const generateReport = useCallback((
    results: ScanResults,
    format: 'markdown' | 'json' | 'csv' | 'txt' | 'html' | 'pdf' | 'findings_summary',
    template: 'detailed' | 'concise' = 'detailed',
    flaggedFindings: Record<string, 'critical' | 'interesting' | null> = {}
  ): Promise<string> => {
    return new Promise((resolve, reject) => {
      if (!workerRef.current) return reject('Worker not initialized');

      setIsProcessing(true);
      const handleMessage = (e: MessageEvent) => {
        if (e.data.type === 'REPORT_GENERATED' && e.data.payload.format === format) {
          workerRef.current?.removeEventListener('message', handleMessage);
          setIsProcessing(false);
          resolve(e.data.payload.documentContent);
        }
      };

      workerRef.current.addEventListener('message', handleMessage);
      workerRef.current.postMessage({
        type: 'GENERATE_REPORT',
        payload: { results, format, template, flaggedFindings }
      });
    });
  }, []);

  const calculateRisk = useCallback((findings: Finding[]): Promise<any> => {
    return new Promise((resolve, reject) => {
      if (!workerRef.current) return reject('Worker not initialized');

      const handleMessage = (e: MessageEvent) => {
        if (e.data.type === 'RISK_CALCULATED') {
          workerRef.current?.removeEventListener('message', handleMessage);
          resolve(e.data.payload);
        }
      };

      workerRef.current.addEventListener('message', handleMessage);
      workerRef.current.postMessage({
        type: 'CALCULATE_RISK',
        payload: { findings }
      });
    });
  }, []);

  return { generateReport, calculateRisk, isProcessing };
}
