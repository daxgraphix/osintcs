/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';

interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'rect' | 'circle';
  width?: string | number;
  height?: string | number;
}

export function Skeleton({ className = '', variant = 'rect', width, height }: SkeletonProps) {
  const style: React.CSSProperties = {
    width: width || '100%',
    height: height || (variant === 'text' ? '1em' : variant === 'circle' ? '40px' : '100%'),
    borderRadius: variant === 'circle' ? '50%' : 'var(--radius-md, 8px)',
    background: 'linear-gradient(90deg, var(--bg-muted) 25%, var(--bg-elevated) 50%, var(--bg-muted) 75%)',
    backgroundSize: '200% 100%',
    animation: 'shimmer 1.5s infinite',
    display: 'inline-block',
  };

  if (variant === 'text') {
    return <span className={`block ${className}`} style={style} />;
  }

  return <span className={`inline-block ${className}`} style={style} />;
}
