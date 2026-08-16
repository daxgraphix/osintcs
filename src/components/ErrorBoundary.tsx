/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type ErrorBoundaryThis = Component<ErrorBoundaryProps, ErrorBoundaryState> & any;

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  declare state: ErrorBoundaryState;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
    this.handleReset = this.handleReset.bind(this);
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('UI crash caught by ErrorBoundary:', error, errorInfo);
  }

  handleReset(this: ErrorBoundaryThis) {
    this.setState({ hasError: false, error: null });
  }

  render() {
    const self = this as ErrorBoundaryThis;
    if (self.state.hasError) {
      if (self.props.fallback) {
        return self.props.fallback;
      }
      return (
        <div className="min-h-screen flex items-center justify-center bg-slate-50 text-slate-800 p-4">
          <div className="max-w-md w-full border border-red-200 bg-white rounded-xl p-6 shadow-sm space-y-4 text-center">
            <div className="w-12 h-12 mx-auto rounded-full bg-red-100 flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-red-600" />
            </div>
            <h2 className="text-lg font-black font-display">Something went wrong</h2>
            <p className="text-xs text-slate-500 font-mono leading-relaxed">
              The application encountered an unexpected error. Your investigation data is preserved in browser storage.
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
              className="w-full py-2.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs uppercase tracking-wider transition-all cursor-pointer"
            >
              Try Again
            </button>
          </div>
        </div>
      );
    }

    return self.props.children as React.ReactNode;
  }
}
