/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface TabErrorBoundaryProps {
  children: ReactNode;
  tabName?: string;
  onReset?: () => void;
}

interface TabErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type TabErrorBoundaryThis = Component<TabErrorBoundaryProps, TabErrorBoundaryState> & any;

export class TabErrorBoundary extends Component<TabErrorBoundaryProps, TabErrorBoundaryState> {
  declare state: TabErrorBoundaryState;

  constructor(props: TabErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
    this.handleReset = this.handleReset.bind(this);
  }

  static getDerivedStateFromError(error: Error): Partial<TabErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const self = this as any;
    console.error(`Tab crash caught by TabErrorBoundary [${self.props.tabName || 'unknown'}]:`, error, errorInfo);
  }

  handleReset(this: TabErrorBoundaryThis) {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  }

  render() {
    const self = this as TabErrorBoundaryThis;
    if (self.state.hasError) {
      return (
        <div className="rounded-xl border border-red-200 bg-white p-6 shadow-sm space-y-4 text-center">
          <div className="w-12 h-12 mx-auto rounded-full bg-red-100 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-red-600" />
          </div>
          <h3 className="text-sm font-black font-display text-slate-900">
            {self.props.tabName ? `${self.props.tabName} tab crashed` : 'This section crashed'}
          </h3>
          <p className="text-xs text-slate-500 font-mono leading-relaxed">
            The report tab encountered an unexpected error. Other tabs and your investigation data are unaffected.
          </p>
          <details className="text-left">
            <summary className="text-[10px] font-mono text-slate-400 cursor-pointer select-none">
              Technical details
            </summary>
            <pre className="mt-2 text-[10px] font-mono bg-slate-50 border border-slate-200 rounded-lg p-3 overflow-x-auto text-red-600 whitespace-pre-wrap break-words">
              {self.state.error?.message}
            </pre>
          </details>
          <button
            onClick={self.handleReset}
            className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs uppercase tracking-wider transition-all cursor-pointer"
          >
            Retry
          </button>
        </div>
      );
    }

    return self.props.children as React.ReactNode;
  }
}
